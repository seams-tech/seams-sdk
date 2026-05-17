import { chainFamilyFromNetwork } from '@/core/config/chains';
import { toAccountId } from '@/core/types/accountIds';
import type { SeamsConfigsReadonly } from '@/core/types/seams';
import {
  thresholdEcdsaChainTargetFromConfig,
  thresholdEcdsaChainTargetKey,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  getStoredThresholdEcdsaSessionRecordByThresholdSessionId,
  listStoredThresholdEd25519SessionRecordsForAccount,
  listThresholdEcdsaRuntimeLanesForSubject,
} from '@/core/signingEngine/session/persistence/records';
import type { listExactSealedSessionsForWallet } from '@/core/signingEngine/session/persistence/sealedSessionStore';
import {
  ecdsaAvailableLaneIdentityKey,
  ed25519AvailableLaneIdentityKey,
  readAvailableSigningLanes,
  warmStatusToAvailableSigningLanesRuntimeClaim,
  type AvailableSigningLanes,
  type AvailableSigningLanesRuntimeClaim,
  type AvailableSigningLanesRuntimeEcdsaRecord,
  type AvailableSigningLanesRuntimeEd25519Record,
  type ReadAvailableSigningLanesInput,
} from '@/core/signingEngine/session/availability/availableSigningLanes';
import { resolveEmailOtpEcdsaWorkerSessionId } from '@/core/signingEngine/session/availability/readiness';
import type { WarmSessionStatusResult } from '@/core/signingEngine/uiConfirm/types';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';

export type EmailOtpPersistedSessionSnapshotPorts = {
  configs: SeamsConfigsReadonly;
  listExactSealedSessionsForWallet: typeof listExactSealedSessionsForWallet;
  readWarmSessionStatusOnly: (sessionId: string) => Promise<WarmSessionStatusResult>;
};

export function configuredEmailOtpEcdsaSnapshotChainTargets(
  configs: SeamsConfigsReadonly,
): ThresholdEcdsaChainTarget[] {
  const targets: ThresholdEcdsaChainTarget[] = [];
  const seen = new Set<string>();
  for (const chain of configs.network.chains) {
    const family = chainFamilyFromNetwork(chain.network);
    if (family !== 'evm' && family !== 'tempo') continue;
    const chainTarget = thresholdEcdsaChainTargetFromConfig(chain);
    const targetKey = thresholdEcdsaChainTargetKey(chainTarget);
    if (seen.has(targetKey)) continue;
    seen.add(targetKey);
    targets.push(chainTarget);
  }
  if (!targets.length) {
    throw new Error('[EmailOtpSession] exact ECDSA snapshot requires configured ECDSA targets');
  }
  return targets;
}

export async function readEmailOtpPersistedSessionSnapshot(
  args: Omit<ReadAvailableSigningLanesInput, 'ecdsaChainTargets'>,
  ports: EmailOtpPersistedSessionSnapshotPorts,
): Promise<AvailableSigningLanes> {
  const accountId = String(toAccountId(args.walletId) || '').trim();
  const listRecords =
    ports.configs.signing.sessionPersistenceMode === 'sealed_refresh_v1'
      ? ports.listExactSealedSessionsForWallet
      : async () => [];

  return await readAvailableSigningLanes(
    {
      ...args,
      walletId: accountId,
      subjectId: args.subjectId,
      ecdsaChainTargets: configuredEmailOtpEcdsaSnapshotChainTargets(ports.configs),
    },
    {
      listSealedRecordsForWallet: async ({ walletId: recordWalletId, filter }) => {
        const listByAuthMethod = async (authMethod: 'email_otp' | 'passkey') => {
          if (filter.curve === 'ecdsa') {
            return await listRecords({
              walletId: recordWalletId,
              filter: {
                authMethod,
                curve: 'ecdsa',
                chainTarget: filter.chainTarget,
              },
            });
          }
          return await listRecords({
            walletId: recordWalletId,
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
        const runtimeRecords: AvailableSigningLanesRuntimeEcdsaRecord[] = [];
        const seen = new Set<string>();
        for (const runtimeLane of listThresholdEcdsaRuntimeLanesForSubject(
          { recordsByLane: new Map() },
          { subjectId },
        )) {
          if (runtimeLane.authMethod !== 'email_otp') continue;
          const record: AvailableSigningLanesRuntimeEcdsaRecord = {
            key: runtimeLane.key,
            authMethod: 'email_otp',
            curve: 'ecdsa',
            chainTarget: runtimeLane.chainTarget,
            thresholdSessionId: runtimeLane.thresholdSessionId,
            walletSigningSessionId: runtimeLane.walletSigningSessionId,
            ...(runtimeLane.remainingUses == null
              ? {}
              : { remainingUses: runtimeLane.remainingUses }),
            ...(runtimeLane.expiresAtMs == null ? {} : { expiresAtMs: runtimeLane.expiresAtMs }),
            ...(runtimeLane.updatedAtMs == null ? {} : { updatedAtMs: runtimeLane.updatedAtMs }),
          };
          const identityKey = ecdsaAvailableLaneIdentityKey(record);
          if (!identityKey || seen.has(identityKey)) continue;
          seen.add(identityKey);
          runtimeRecords.push(record);
        }
        return runtimeRecords;
      },
      listRuntimeEd25519RecordsForAccount: async ({ accountId: recordAccountId }) => {
        const records: AvailableSigningLanesRuntimeEd25519Record[] = [];
        const seen = new Set<string>();
        const pushRecord = (record: AvailableSigningLanesRuntimeEd25519Record) => {
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
            remainingUses: runtimeRecord.remainingUses,
            expiresAtMs: runtimeRecord.expiresAtMs,
            updatedAtMs: runtimeRecord.updatedAtMs,
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
              ecdsaRecord?.source === 'email_otp'
                ? resolveEmailOtpEcdsaWorkerSessionId(ecdsaRecord)
                : sessionId;
            const status = await ports.readWarmSessionStatusOnly(statusSessionId);
            claims.set(
              sessionId,
              warmStatusToAvailableSigningLanesRuntimeClaim({ sessionId, status }),
            );
          }),
        );
        return claims;
      },
    },
  );
}
