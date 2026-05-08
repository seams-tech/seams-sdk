import { toAccountId } from '@/core/types/accountIds';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { WarmSessionStatusResult } from '../../uiConfirm/types';
import { resolveEmailOtpEcdsaWorkerSessionId } from './readiness';
import {
  getStoredThresholdEcdsaSessionRecordByThresholdSessionId,
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
};

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
            const statusSessionId =
              ecdsaRecord?.source === SIGNER_AUTH_METHODS.emailOtp
                ? resolveEmailOtpEcdsaWorkerSessionId(ecdsaRecord)
                : sessionId;
            const status = await deps.statusReader
              .getWarmSessionStatus({ sessionId: statusSessionId })
              .catch(() => null);
            claims.set(
              sessionId,
              status ? warmStatusToAvailableSigningLanesRuntimeClaim({ sessionId, status }) : null,
            );
          }),
        );
        return claims;
      },
    },
  );
}
