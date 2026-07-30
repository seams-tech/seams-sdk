import { chainFamilyFromNetwork } from '@/core/config/chains';
import type { SeamsConfigsReadonly } from '@/core/types/seams';
import {
  thresholdEcdsaChainTargetFromConfig,
  thresholdEcdsaChainTargetKey,
  toWalletId,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  listStoredThresholdEd25519SessionLaneRecordsForWallet,
  thresholdEd25519LaneCandidateFromSessionRecord,
} from '@/core/signingEngine/session/persistence/records';
import { laneCandidateAuthMethod } from '@/core/signingEngine/session/identity/laneIdentity';
import type { listExactSealedSessionsForWallet } from '@/core/signingEngine/session/persistence/sealedSessionStore';
import {
  ed25519AvailableLaneIdentityKey,
  readAvailableSigningLanes,
  warmStatusToAvailableLaneStateAdvisory,
  type AvailableSigningLanes,
  type AvailableLaneStateAdvisory,
  type AvailableSigningLanesRuntimeEd25519Record,
  type ReadAvailableSigningLanesInput,
} from '@/core/signingEngine/session/availability/availableSigningLanes';
import type { WarmSessionStatusResult } from '@/core/signingEngine/uiConfirm/uiConfirm.types';

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
  const walletId = String(toWalletId(args.walletId) || '').trim();
  const listRecords =
    ports.configs.signing.sessionPersistenceMode === 'sealed_refresh_v1'
      ? ports.listExactSealedSessionsForWallet
      : async () => [];

  return await readAvailableSigningLanes(
    {
      ...args,
      walletId,
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
      listRuntimeEd25519RecordsForWallet: async ({ walletId: recordWalletId }) => {
        const records: AvailableSigningLanesRuntimeEd25519Record[] = [];
        const seen = new Set<string>();
        const pushRecord = (record: AvailableSigningLanesRuntimeEd25519Record) => {
          const identityKey = ed25519AvailableLaneIdentityKey(record);
          if (!identityKey || seen.has(identityKey)) return;
          seen.add(identityKey);
          records.push(record);
        };
        for (const runtimeRecord of listStoredThresholdEd25519SessionLaneRecordsForWallet(
          recordWalletId,
        )) {
          const laneCandidate = thresholdEd25519LaneCandidateFromSessionRecord({
            record: runtimeRecord,
          });
          if (!laneCandidate) continue;
          const candidateAuthMethod = laneCandidateAuthMethod(laneCandidate);
          if (args.authMethod && args.authMethod !== candidateAuthMethod) continue;
          pushRecord({
            auth: laneCandidate.auth,
            curve: 'ed25519',
            chain: 'near',
            walletId: runtimeRecord.walletId,
            nearAccountId: runtimeRecord.nearAccountId,
            nearEd25519SigningKeyId: runtimeRecord.nearEd25519SigningKeyId,
            signerSlot: laneCandidate.signerSlot,
            routerAbNormalSigning: runtimeRecord.routerAbNormalSigning,
            thresholdSessionId: runtimeRecord.thresholdSessionId,
            signingGrantId: String(runtimeRecord.signingGrantId || '').trim(),
            source: 'runtime_session_record',
            remainingUses: runtimeRecord.remainingUses,
            expiresAtMs: runtimeRecord.expiresAtMs,
            updatedAtMs: runtimeRecord.updatedAtMs,
          });
        }
        return records;
      },
      readWarmStatusAdvisoriesForSessions: async (sessionIds) => {
        const advisories = new Map<string, AvailableLaneStateAdvisory | null>();
        await Promise.all(
          sessionIds.map(async (sessionId) => {
            const status = await ports.readWarmSessionStatusOnly(sessionId);
            advisories.set(
              sessionId,
              warmStatusToAvailableLaneStateAdvisory({ status }),
            );
          }),
        );
        return advisories;
      },
    },
  );
}
