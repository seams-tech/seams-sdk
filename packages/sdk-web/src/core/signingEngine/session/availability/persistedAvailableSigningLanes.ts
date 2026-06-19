import { toAccountId } from '@/core/types/accountIds';
import type { AccountId } from '@/core/types/accountIds';
import type { SigningSessionStatus } from '@/core/types/seams';
import { classifyThresholdEcdsaSessionRecordRoleLocalState } from '../persistence/ecdsaRoleLocalRecords';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { thresholdEcdsaChainTargetKey } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { WarmSessionStatusResult } from '../../uiConfirm/types';
import {
  buildEcdsaLaneBudgetStatusCheck,
  buildThresholdBudgetStatusCheck,
  ed25519WalletBudgetOwner,
  type SigningSessionBudgetStatusCheck,
} from '../budget/budget';
import {
  getStoredThresholdEd25519SessionRecordByThresholdSessionId,
  getThresholdEcdsaSessionRecordByKey,
  listStoredThresholdEd25519SessionRecordsForAccount,
  listThresholdEcdsaRuntimeLanesForWallet,
  thresholdEcdsaSessionRecordReadModel,
  type ThresholdEcdsaSessionStoreDeps,
} from '../persistence/records';
import {
  listEcdsaSealedSessionsForWallet,
  listExactSealedSessionsForWallet,
  type SigningSessionSealedStoreRecord,
} from '../persistence/sealedSessionStore';
import {
  ed25519AvailableLaneIdentityKey,
  readAvailableSigningLanes,
  runtimeEcdsaAvailableLaneIdentityKey,
  runtimeEcdsaRecordClaimKey,
  runtimeRecordPolicyClaim,
  warmStatusToAvailableSigningLanesRuntimeClaim,
  type ReadAvailableSigningLanesForSigningInput,
  type ReadAvailableSigningLanesInput,
  type AvailableSigningLanes,
  type AvailableSigningLanesRuntimeClaim,
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

function applyWalletBudgetStatusToRuntimeClaim(args: {
  sessionId: string;
  localClaim: AvailableSigningLanesRuntimeClaim | null;
  walletBudgetStatus: SigningSessionStatus | null;
}): AvailableSigningLanesRuntimeClaim | null {
  const budgetStatus = args.walletBudgetStatus;
  if (!budgetStatus) return args.localClaim;
  if (budgetStatus.status === 'active') {
    if (args.localClaim?.state !== 'warm') return args.localClaim;
    const budgetExpiresAtMs = Math.floor(Number(budgetStatus.expiresAtMs) || 0);
    return {
      state: 'warm',
      thresholdSessionId: args.sessionId,
      remainingUses: Math.max(0, Math.floor(Number(budgetStatus.remainingUses) || 0)),
      expiresAtMs: budgetExpiresAtMs > 0 ? budgetExpiresAtMs : args.localClaim.expiresAtMs,
    };
  }
  if (budgetStatus.status === 'not_found') {
    return { state: 'missing', thresholdSessionId: args.sessionId, code: 'wallet_budget_not_found' };
  }
  if (budgetStatus.status === 'expired') return { state: 'expired', thresholdSessionId: args.sessionId };
  if (budgetStatus.status === 'exhausted') {
    return { state: 'exhausted', thresholdSessionId: args.sessionId, remainingUses: 0 };
  }
  return {
    state: 'unavailable',
    thresholdSessionId: args.sessionId,
    code: budgetStatus.status,
  };
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

export async function readPersistedAvailableSigningLanesForTargets(
  deps: PersistedAvailableSigningLanesDeps,
  args: Omit<ReadAvailableSigningLanesInput, 'ecdsaChainTargets'> & {
    ecdsaChainTargets: readonly ThresholdEcdsaChainTarget[];
  },
): Promise<AvailableSigningLanes> {
  const walletAccountId = toAccountId(args.walletId);
  const walletId = String(walletAccountId).trim();
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
          const companionEcdsaRecords = (
            await Promise.all(
              args.ecdsaChainTargets.map(
                async (chainTarget) =>
                  await listExactSealedSessionsForWallet({
                    walletId: recordWalletId,
                    filter: {
                      authMethod: 'email_otp',
                      curve: 'ecdsa',
                      chainTarget,
                    },
                  }),
              ),
            )
          )
            .flat()
            .filter(
              (record) => String(record.thresholdSessionIds?.ed25519 || '').trim().length > 0,
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
          if (args.authMethod && args.authMethod !== runtimeLane.authMethod) continue;
          if (!runtimeLane.routerAbEcdsaHssNormalSigning) continue;
          const baseRecord = {
            key: runtimeLane.key,
            routerAbEcdsaHssNormalSigning: runtimeLane.routerAbEcdsaHssNormalSigning,
            keyHandle: runtimeLane.keyHandle,
            ...(runtimeLane.verifiedPublicFacts
              ? { verifiedPublicFacts: runtimeLane.verifiedPublicFacts }
              : {}),
            thresholdEcdsaPublicKeyB64u: runtimeLane.thresholdEcdsaPublicKeyB64u,
            curve: 'ecdsa',
            chainTarget: runtimeLane.chainTarget,
            thresholdSessionId: runtimeLane.thresholdSessionId,
            signingGrantId: runtimeLane.signingGrantId,
            ...(runtimeLane.remainingUses == null
              ? {}
              : { remainingUses: runtimeLane.remainingUses }),
            ...(runtimeLane.expiresAtMs == null ? {} : { expiresAtMs: runtimeLane.expiresAtMs }),
            ...(runtimeLane.updatedAtMs == null ? {} : { updatedAtMs: runtimeLane.updatedAtMs }),
          } satisfies Omit<AvailableSigningLanesRuntimeEcdsaRecord, 'authMethod' | 'resolvedKey'>;
          await pushRuntimeEcdsaRecord(
            records,
            seen,
            runtimeLane.authMethod === 'passkey'
              ? {
                  ...baseRecord,
                  authMethod: 'passkey',
                  ...(runtimeLane.resolvedKey ? { resolvedKey: runtimeLane.resolvedKey } : {}),
                }
              : {
                  ...baseRecord,
                  authMethod: 'email_otp',
                },
          );
        }
        return records;
      },
      listRuntimeEd25519RecordsForAccount: async ({ accountId: recordAccountId }) => {
        const records: AvailableSigningLanesRuntimeEd25519Record[] = [];
        const seen = new Set<string>();
        const pushRecord = (record: AvailableSigningLanesRuntimeEd25519Record): void => {
          const identityKey = ed25519AvailableLaneIdentityKey(record);
          if (!identityKey || seen.has(identityKey)) return;
          seen.add(identityKey);
          records.push(record);
        };
        for (const runtimeRecord of listStoredThresholdEd25519SessionRecordsForAccount(
          recordAccountId,
        )) {
          const authMethod =
            runtimeRecord.source === SIGNER_AUTH_METHODS.emailOtp ? 'email_otp' : 'passkey';
          if (args.authMethod && args.authMethod !== authMethod) continue;
          if (!runtimeRecord.routerAbNormalSigning) continue;
          pushRecord({
            authMethod,
            curve: 'ed25519',
            chain: 'near',
            routerAbNormalSigning: runtimeRecord.routerAbNormalSigning,
            thresholdSessionId: runtimeRecord.thresholdSessionId,
            signingGrantId: String(runtimeRecord.signingGrantId || '').trim(),
            remainingUses: runtimeRecord.remainingUses,
            expiresAtMs: runtimeRecord.expiresAtMs,
            updatedAtMs: runtimeRecord.updatedAtMs,
          });
        }
        return records;
      },
      readRuntimeEcdsaClaimsForRecords: async (runtimeRecords) => {
        const claims = new Map<string, AvailableSigningLanesRuntimeClaim | null>();
        await Promise.all(
          runtimeRecords.map(async (runtimeRecord) => {
            const claimKey = runtimeEcdsaRecordClaimKey(runtimeRecord);
            if (!claimKey) return;
            const keyHandle = String(runtimeRecord.keyHandle || '').trim();
            if (!keyHandle) {
              claims.set(claimKey, null);
              return;
            }
            const sessionId = String(runtimeRecord.thresholdSessionId || '').trim();
            const signingGrantId = String(
              runtimeRecord.signingGrantId || '',
            ).trim();
            const ecdsaRecord = getThresholdEcdsaSessionRecordByKey(deps.ecdsaSessions, {
              walletId: toAccountId(runtimeRecord.key.walletId),
              keyHandle,
              authMethod: runtimeRecord.authMethod,
              curve: 'ecdsa',
              chainTarget: runtimeRecord.chainTarget,
              signingGrantId,
              thresholdSessionId: sessionId,
            });
            let localClaim: AvailableSigningLanesRuntimeClaim | null = null;
            if (!ecdsaRecord) {
              localClaim = null;
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
                localClaim = status
                  ? warmStatusToAvailableSigningLanesRuntimeClaim({ thresholdSessionId: sessionId, status })
                  : null;
              } else if (
                roleLocalState.kind === 'ready_email_otp_role_local_material_v1' &&
                roleLocalState.inlineSigningMaterial.kind === 'role_local_ready_state_blob'
              ) {
                localClaim = runtimeRecordPolicyClaim({
                  thresholdSessionId: sessionId,
                  remainingUses: ecdsaRecord.remainingUses,
                  expiresAtMs: ecdsaRecord.expiresAtMs,
                });
              } else {
                localClaim = null;
              }
            } else {
              const status = await deps.statusReader
                .getWarmSessionStatus({ sessionId })
                .catch(() => null);
              localClaim = status
                ? warmStatusToAvailableSigningLanesRuntimeClaim({ thresholdSessionId: sessionId, status })
                : null;
            }
            const walletBudgetStatus =
              ecdsaRecord && deps.getWalletSigningBudgetStatus
                ? await deps
                    .getWalletSigningBudgetStatus(
                      buildEcdsaLaneBudgetStatusCheck({
                        key: thresholdEcdsaSessionRecordReadModel(ecdsaRecord).key,
                        keyHandle: ecdsaRecord.keyHandle,
                        chainTarget: ecdsaRecord.chainTarget,
                        signingGrantId,
                        thresholdSessionId: ecdsaRecord.thresholdSessionId,
                      }),
                    )
                    .catch(() => null)
                : null;
            claims.set(
              claimKey,
              applyWalletBudgetStatusToRuntimeClaim({
                sessionId,
                localClaim,
                walletBudgetStatus,
              }),
            );
          }),
        );
        return claims;
      },
      readRuntimeClaimsForSessions: async (sessionIds) => {
        const claims = new Map<string, AvailableSigningLanesRuntimeClaim | null>();
        await Promise.all(
          sessionIds.map(async (sessionId) => {
            const ed25519Record =
              getStoredThresholdEd25519SessionRecordByThresholdSessionId(sessionId);
            let localClaim: AvailableSigningLanesRuntimeClaim | null = null;
            if (ed25519Record?.source === SIGNER_AUTH_METHODS.emailOtp) {
              if (
                String(ed25519Record.ed25519HssMaterialHandle || '').trim() &&
                String(ed25519Record.ed25519HssMaterialBindingDigest || '').trim() &&
                String(ed25519Record.clientVerifyingShareB64u || '').trim()
              ) {
                localClaim = runtimeRecordPolicyClaim({
                  thresholdSessionId: sessionId,
                  remainingUses: ed25519Record.remainingUses,
                  expiresAtMs: ed25519Record.expiresAtMs,
                });
              } else {
                const status = await deps.getEmailOtpWarmSessionStatus(sessionId).catch(() => null);
                localClaim = status
                  ? warmStatusToAvailableSigningLanesRuntimeClaim({ thresholdSessionId: sessionId, status })
                  : null;
              }
            } else {
              const status = await deps.statusReader
                .getWarmSessionStatus({ sessionId })
                .catch(() => null);
              localClaim = status
                ? warmStatusToAvailableSigningLanesRuntimeClaim({ thresholdSessionId: sessionId, status })
                : null;
            }
            const signingGrantId = String(
              ed25519Record?.signingGrantId || '',
            ).trim();
            const walletBudgetStatus =
              signingGrantId && deps.getWalletSigningBudgetStatus
                ? await deps
                    .getWalletSigningBudgetStatus(
                      buildThresholdBudgetStatusCheck({
                        owner: ed25519WalletBudgetOwner(walletAccountId),
                        signingGrantId,
                        targetThresholdSessionIds: [sessionId],
                      }),
                    )
                    .catch(() => null)
                : null;
            claims.set(
              sessionId,
              applyWalletBudgetStatusToRuntimeClaim({
                sessionId,
                localClaim,
                walletBudgetStatus,
              }),
            );
          }),
        );
        return claims;
      },
    },
  );
}
