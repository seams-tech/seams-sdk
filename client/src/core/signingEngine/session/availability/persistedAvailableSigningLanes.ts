import { toAccountId } from '@/core/types/accountIds';
import type { AccountId } from '@/core/types/accountIds';
import type { SigningSessionStatus } from '@/core/types/seams';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { WarmSessionStatusResult } from '../../uiConfirm/types';
import { resolveEmailOtpEcdsaWorkerSessionId } from './readiness';
import {
  getStoredThresholdEcdsaSessionRecordByThresholdSessionId,
  getStoredThresholdEd25519SessionRecordByThresholdSessionId,
  listStoredThresholdEd25519SessionRecordsForAccount,
  listThresholdEcdsaRuntimeLanesForSubject,
  type ThresholdEcdsaSessionStoreDeps,
} from '../persistence/records';
import {
  listExactSealedSessionsForAccount,
  type SigningSessionSealedStoreRecord,
} from '../persistence/sealedSessionStore';
import {
  ecdsaAvailableLaneIdentityKey,
  ed25519AvailableLaneIdentityKey,
  readAvailableSigningLanes,
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
  getWalletSigningBudgetStatus?: (args: {
    nearAccountId: AccountId | string;
    walletSigningSessionId: string;
    targetThresholdSessionIds?: string[];
    targetBackingMaterialSessionIds?: string[];
  }) => Promise<SigningSessionStatus | null>;
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
    return {
      state: 'warm',
      sessionId: args.sessionId,
      remainingUses: Math.max(0, Math.floor(Number(budgetStatus.remainingUses) || 0)),
      ...(Number(budgetStatus.expiresAtMs) > 0
        ? { expiresAtMs: Math.floor(Number(budgetStatus.expiresAtMs)) }
        : args.localClaim.expiresAtMs
          ? { expiresAtMs: args.localClaim.expiresAtMs }
          : {}),
    };
  }
  if (budgetStatus.status === 'not_found') {
    return { state: 'missing', sessionId: args.sessionId, code: 'wallet_budget_not_found' };
  }
  if (budgetStatus.status === 'expired') return { state: 'expired', sessionId: args.sessionId };
  if (budgetStatus.status === 'exhausted') {
    return { state: 'exhausted', sessionId: args.sessionId };
  }
  return {
    state: 'unavailable',
    sessionId: args.sessionId,
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
    return await readPersistedAvailableSigningLanesForTargets(deps, availableLanesArgs);
  }
  const { curve, ...availableLanesArgs } = args;
  return await readPersistedAvailableSigningLanes(deps, availableLanesArgs, defaultEcdsaChainTargets);
}

export async function readPersistedAvailableSigningLanesForTargets(
  deps: PersistedAvailableSigningLanesDeps,
  args: Omit<ReadAvailableSigningLanesInput, 'ecdsaChainTargets'> & {
    ecdsaChainTargets: readonly ThresholdEcdsaChainTarget[];
  },
): Promise<AvailableSigningLanes> {
  const accountId = String(toAccountId(args.walletId) || '').trim();
  const pushRuntimeEcdsaRecord = (
    records: AvailableSigningLanesRuntimeEcdsaRecord[],
    seen: Set<string>,
    record: AvailableSigningLanesRuntimeEcdsaRecord,
  ): void => {
    const identityKey = ecdsaAvailableLaneIdentityKey(record);
    if (!identityKey || seen.has(identityKey)) return;
    seen.add(identityKey);
    records.push(record);
  };

  return await readAvailableSigningLanes(
    {
      ...args,
      walletId: accountId,
      subjectId: args.subjectId,
      ecdsaChainTargets: args.ecdsaChainTargets,
    },
    {
      listSealedRecordsForAccount: async ({ accountId: recordAccountId, filter }) => {
        const listByAuthMethod = async (
          authMethod: 'email_otp' | 'passkey',
        ): Promise<SigningSessionSealedStoreRecord[]> => {
          if (filter.curve === 'ecdsa') {
            return await listExactSealedSessionsForAccount({
              accountId: recordAccountId,
              filter: {
                authMethod,
                curve: 'ecdsa',
                chainTarget: filter.chainTarget,
              },
            });
          }
          return await listExactSealedSessionsForAccount({
            accountId: recordAccountId,
            filter: { authMethod, curve: 'ed25519' },
          });
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
      listRuntimeEcdsaLanesForSubject: async ({ subjectId }) => {
        const records: AvailableSigningLanesRuntimeEcdsaRecord[] = [];
        const seen = new Set<string>();
        for (const runtimeLane of listThresholdEcdsaRuntimeLanesForSubject(deps.ecdsaSessions, {
          subjectId,
        })) {
          if (args.authMethod && args.authMethod !== runtimeLane.authMethod) continue;
          pushRuntimeEcdsaRecord(records, seen, {
            subjectId: runtimeLane.subjectId,
            authMethod: runtimeLane.authMethod,
            curve: 'ecdsa',
            chainTarget: runtimeLane.chainTarget,
            ecdsaThresholdKeyId: runtimeLane.ecdsaThresholdKeyId,
            signingRootId: runtimeLane.signingRootId,
            signingRootVersion: runtimeLane.signingRootVersion,
            thresholdSessionId: runtimeLane.thresholdSessionId,
            walletSigningSessionId: runtimeLane.walletSigningSessionId,
          });
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
          pushRecord({
            authMethod,
            curve: 'ed25519',
            chain: 'near',
            thresholdSessionId: runtimeRecord.thresholdSessionId,
            walletSigningSessionId: runtimeRecord.walletSigningSessionId,
          });
        }
        return records;
      },
      readRuntimeClaimsForSessions: async (sessionIds) => {
        const claims = new Map<string, AvailableSigningLanesRuntimeClaim | null>();
        await Promise.all(
          sessionIds.map(async (sessionId) => {
            const ecdsaRecord = getStoredThresholdEcdsaSessionRecordByThresholdSessionId(sessionId);
            const ed25519Record =
              ecdsaRecord ? null : getStoredThresholdEd25519SessionRecordByThresholdSessionId(sessionId);
            const statusSessionId =
              ecdsaRecord?.source === SIGNER_AUTH_METHODS.emailOtp
                ? resolveEmailOtpEcdsaWorkerSessionId(ecdsaRecord)
                : sessionId;
            const status = await deps.statusReader
              .getWarmSessionStatus({ sessionId: statusSessionId })
              .catch(() => null);
            const localClaim = status
              ? warmStatusToAvailableSigningLanesRuntimeClaim({ sessionId, status })
              : null;
            const walletSigningSessionId = String(
              ecdsaRecord?.walletSigningSessionId || ed25519Record?.walletSigningSessionId || '',
            ).trim();
            const walletBudgetStatus =
              walletSigningSessionId && deps.getWalletSigningBudgetStatus
                ? await deps
                    .getWalletSigningBudgetStatus({
                      nearAccountId: accountId,
                      walletSigningSessionId,
                      targetThresholdSessionIds: [sessionId],
                    })
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
